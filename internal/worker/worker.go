package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/dicedb/dice/config"
	"github.com/dicedb/dice/internal/auth"
	"github.com/dicedb/dice/internal/clientio"
	"github.com/dicedb/dice/internal/clientio/iohandler"
	"github.com/dicedb/dice/internal/clientio/requestparser"
	"github.com/dicedb/dice/internal/cmd"
	diceerrors "github.com/dicedb/dice/internal/errors"
	"github.com/dicedb/dice/internal/eval"
	"github.com/dicedb/dice/internal/ops"
	"github.com/dicedb/dice/internal/shard"
)

// Worker interface
type Worker interface {
	ID() string
	Start(context.Context) error
	Stop() error
}

type BaseWorker struct {
	id              string
	ioHandler       iohandler.IOHandler
	parser          requestparser.Parser
	shardManager    *shard.ShardManager
	respChan        chan *ops.StoreResponse
	Session         *auth.Session
	globalErrorChan chan error
	logger          *slog.Logger
}

func NewWorker(wid string, respChan chan *ops.StoreResponse,
	ioHandler iohandler.IOHandler, parser requestparser.Parser,
	shardManager *shard.ShardManager, gec chan error,
	logger *slog.Logger) *BaseWorker {
	return &BaseWorker{
		id:              wid,
		ioHandler:       ioHandler,
		parser:          parser,
		shardManager:    shardManager,
		globalErrorChan: gec,
		respChan:        respChan,
		logger:          logger,
		Session:         auth.NewSession(),
	}
}

func (w *BaseWorker) ID() string {
	return w.id
}

func (w *BaseWorker) Start(ctx context.Context) error {
	errChan := make(chan error, 1)
	for {
		select {
		case <-ctx.Done():
			err := w.Stop()
			if err != nil {
				w.logger.Warn("Error stopping worker:", slog.String("workerID", w.id), slog.Any("error", err))
			}
			return ctx.Err()
		case err := <-errChan:
			if err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
					w.logger.Error("Connection closed for worker", slog.String("workerID", w.id), slog.Any("error", err))
					return err
				}
			}
			return fmt.Errorf("error writing response: %w", err)
		default:
			data, err := w.ioHandler.Read(ctx)
			if err != nil {
				w.logger.Debug("Read error, connection closed possibly", slog.String("workerID", w.id), slog.Any("error", err))
				return err
			}
			cmds, err := w.parser.Parse(data)
			if err != nil {
				err = w.ioHandler.Write(ctx, err)
				if err != nil {
					w.logger.Debug("Write error, connection closed possibly", slog.String("workerID", w.id), slog.Any("error", err))
					return err
				}
			}
			if len(cmds) == 0 {
				err = w.ioHandler.Write(ctx, "ERR: Invalid request")
				if err != nil {
					w.logger.Debug("Write error, connection closed possibly", slog.String("workerID", w.id), slog.Any("error", err))
					return err
				}
				continue
			}

			// DiceDB supports clients to send only one request at a time
			// We also need to ensure that the client is blocked until the response is received
			if len(cmds) > 1 {
				err = w.ioHandler.Write(ctx, "ERR: Multiple commands not supported")
				if err != nil {
					w.logger.Debug("Write error, connection closed possibly", slog.String("workerID", w.id), slog.Any("error", err))
					return err
				}
			}

			err = w.isAuthenticated(cmds[0])
			if err != nil {
				werr := w.ioHandler.Write(ctx, err)
				if werr != nil {
					w.logger.Debug("Write error, connection closed possibly", slog.Any("error", errors.Join(err, werr)))
					return errors.Join(err, werr)
				}
			}
			// ExecuteCommand executes the command and return the response back to the client
			func(errChan chan error) {
				execctx, cancel := context.WithTimeout(ctx, 1*time.Second) // Timeout if
				defer cancel()
				err = w.executeCommand(execctx, cmds[0])
				if err != nil {
					w.logger.Error("Error executing command", slog.String("workerID", w.id), slog.Any("error", err))
					if errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ETIMEDOUT) {
						w.logger.Debug("Connection closed for worker", slog.String("workerID", w.id), slog.Any("error", err))
						errChan <- err
					}
				}
			}(errChan)
		}
	}
}

func (w *BaseWorker) executeCommand(ctx context.Context, redisCmd *cmd.RedisCmd) error {
	deps := &ExecuteCommandDeps{
		ShardManager:    w.shardManager,
		WorkerID:        w.id,
		RespChan:        w.respChan,
		Logger:          w.logger,
		GlobalErrorChan: w.globalErrorChan,
	}
	result, err := ExecuteCommand(ctx, redisCmd, deps, false, false)
	// Write the result back to the client
	if err != nil {
		return err
	}

	switch result.Action {
	case CmdPing:
		meta := CommandsMeta[redisCmd.Cmd]
		err := w.ioHandler.Write(ctx, meta.WorkerCommandHandler(redisCmd.Args))
		return err
	case CmdAuth:
		err := w.ioHandler.Write(ctx, w.RespAuth(redisCmd.Args))
		return err
	}

	return nil
}

func (w *BaseWorker) isAuthenticated(redisCmd *cmd.RedisCmd) error {
	if redisCmd.Cmd != auth.Cmd && !w.Session.IsActive() {
		return errors.New("NOAUTH Authentication required")
	}

	return nil
}

// RespAuth returns with an encoded "OK" if the user is authenticated
// If the user is not authenticated, it returns with an encoded error message
func (w *BaseWorker) RespAuth(args []string) []byte {
	// Check for incorrect number of arguments (arity error).
	if len(args) < 1 || len(args) > 2 {
		return diceerrors.NewErrArity("AUTH") // Return an error if the number of arguments is not equal to 1.
	}

	if config.DiceConfig.Auth.Password == "" {
		return diceerrors.NewErrWithMessage("AUTH <password> called without any password configured for the default user. Are you sure your configuration is correct?")
	}

	username := config.DiceConfig.Auth.UserName
	var password string

	if len(args) == 1 {
		password = args[0]
	} else {
		username, password = args[0], args[1]
	}

	if err := w.Session.Validate(username, password); err != nil {
		return clientio.Encode(err, false)
	}

	return clientio.RespOK
}

func (w *BaseWorker) Stop() error {
	w.logger.Info("Stopping worker", slog.String("workerID", w.id))
	w.Session.Expire()
	return nil
}

type ExecuteCommandDeps struct {
	ShardManager    *shard.ShardManager
	WorkerID        string
	RespChan        chan *ops.StoreResponse
	Logger          *slog.Logger
	GlobalErrorChan chan error
}

type CommandResponse struct {
	ResponseData interface{}
	Error        error
	Action       string
	Args         []string
}

func ExecuteCommand(ctx context.Context, redisCmd *cmd.RedisCmd, deps *ExecuteCommandDeps, isHttpOp, isWebsocketOp bool) (*CommandResponse, error) {
	cmdList := make([]*cmd.RedisCmd, 0)
	meta, ok := CommandsMeta[redisCmd.Cmd]
	if !ok {
		cmdList = append(cmdList, redisCmd)
	} else {
		switch meta.CmdType {
		case Global:
			return handleGlobalCommand(redisCmd)
		case Custom:
			return handleCustomCommand(redisCmd, deps)
		case SingleShard:
			cmdList = append(cmdList, redisCmd)
		case MultiShard:
			cmdList = meta.decomposeCommand(redisCmd)
		}
	}

	err := scatter(ctx, cmdList, deps, isHttpOp, isWebsocketOp)
	if err != nil {
		return nil, err
	}

	responseData, err := gather(ctx, redisCmd.Cmd, len(cmdList), meta.CmdType, deps)
	if err != nil {
		return nil, err
	}

	return &CommandResponse{ResponseData: responseData}, nil
}

func handleGlobalCommand(redisCmd *cmd.RedisCmd) (*CommandResponse, error) {
	return &CommandResponse{Args: redisCmd.Args, Action: CmdPing}, nil
}

func handleCustomCommand(redisCmd *cmd.RedisCmd, deps *ExecuteCommandDeps) (*CommandResponse, error) {
	switch redisCmd.Cmd {
	case CmdAuth:
		return &CommandResponse{Args: redisCmd.Args, Action: CmdAuth}, nil
	case CmdAbort:
		deps.Logger.Info("Received ABORT command, initiating server shutdown", slog.String("workerID", deps.WorkerID))
		// Send the abort error to the global error channel
		deps.GlobalErrorChan <- diceerrors.ErrAborted
		return &CommandResponse{}, nil
	default:
		return nil, fmt.Errorf("unknown custom command: %s", redisCmd.Cmd)
	}
}

func scatter(ctx context.Context, cmds []*cmd.RedisCmd, deps *ExecuteCommandDeps, isHttpOp, isWebsocketOp bool) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		for i := uint8(0); i < uint8(len(cmds)); i++ {
			var rc chan *ops.StoreOp
			var sid shard.ShardID
			var key string
			if len(cmds[i].Args) > 0 {
				key = cmds[i].Args[0]
			} else {
				key = cmds[i].Cmd
			}

			sid, rc = deps.ShardManager.GetShardInfo(key)
			if rc == nil {
				deps.Logger.Error("Shard channel is nil", slog.String("workerID", deps.WorkerID), slog.Any("key", key))
				return fmt.Errorf("shard channel is nil for key: %s", key)
			}

			rc <- &ops.StoreOp{
				SeqID:     i,
				RequestID: cmds[i].RequestID,
				Cmd:       cmds[i],
				WorkerID:  deps.WorkerID,
				ShardID:   sid,
				Client:    nil,
				HTTPOp: isHttpOp,
				WebsocketOp: isWebsocketOp,
			}
		}
	}

	return nil
}

func gather(ctx context.Context, c string, numCmds int, ct CmdType, deps *ExecuteCommandDeps) (interface{}, error) {
	var evalResp []eval.EvalResponse
	for numCmds != 0 {
		select {
		case <-ctx.Done():
			deps.Logger.Error("Timed out waiting for response from shards", slog.String("workerID", deps.WorkerID), slog.Any("error", ctx.Err()))
			return nil, ctx.Err()
		case resp, ok := <-deps.RespChan:
			if ok {
				evalResp = append(evalResp, *resp.EvalResponse)
			} else {
				deps.Logger.Warn("Response channel closed", slog.String("workerID", deps.WorkerID))
				numCmds--
			}
			numCmds--
		case sError, ok := <-deps.ShardManager.ShardErrorChan:
			if ok {
				deps.Logger.Error("Error from shard", slog.String("workerID", deps.WorkerID), slog.Any("error", sError))
			}
		}
	}

	// Process the responses based on the command type
	val, ok := CommandsMeta[c]
	if !ok {
		// If the command is not in CommandsMeta, handle it as a default case
		if len(evalResp) == 0 {
			return nil, fmt.Errorf("no response from shards for command: %s", c)
		}
		if evalResp[0].Error != nil {
			return nil, evalResp[0].Error
		}

		return evalResp[0].Result, nil
	}

	// Handle based on command type
	switch ct {
	case SingleShard, Custom:
		if len(evalResp) == 0 {
			return nil, fmt.Errorf("no response from shards for command: %s", c)
		}
		if evalResp[0].Error != nil {
			return nil, evalResp[0].Error
		}

		return evalResp[0].Result, nil
	case MultiShard:
		// For MultiShard commands, compose the response from multiple shard responses
		responseData := val.composeResponse(evalResp...)
		return responseData, nil
	default:
		deps.Logger.Error("Unknown command type", slog.String("workerID", deps.WorkerID), slog.String("command", c))
		return nil, diceerrors.ErrInternalServer
	}
}
