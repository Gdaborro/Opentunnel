package releasebuild

import (
	"context"
	"errors"
)

func CheckFrozenSource(ctx context.Context, dir, commit string) error {
	files, err := frozenGitFiles(ctx, dir, commit)
	if err != nil {
		return err
	}
	var total int64
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := gitBlob(ctx, dir, file)
		if err != nil {
			return err
		}
		total += int64(len(data))
		if total > MaxExpandedSourceBytes {
			return errors.New("frozen source aggregate byte bound exceeded")
		}
		if err := verifyWorktreeBlob(dir, file, data); err != nil {
			return err
		}
	}
	_, err = frozenGitFiles(ctx, dir, commit)
	return err
}
