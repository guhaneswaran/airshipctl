package workflow

import (
	"fmt"
	"io"

	"github.com/argoproj/pkg/humanize"
	"github.com/spf13/cobra"

	"github.com/ian-howell/airshipctl/pkg/apis/workflow/v1alpha1"
	"github.com/ian-howell/airshipctl/pkg/util"
	wf "github.com/ian-howell/airshipctl/pkg/workflow"
	"github.com/ian-howell/airshipctl/pkg/workflow/environment"
	wfutil "github.com/ian-howell/airshipctl/pkg/workflow/util"
)

// NewWorkflowListCommand is a command for listing argo workflows
func NewWorkflowListCommand(settings *environment.Settings) *cobra.Command {
	workflowListCmd := &cobra.Command{
		Use:     "list",
		Short:   "list workflows",
		Aliases: []string{"ls"},
		Run: func(cmd *cobra.Command, args []string) {
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "debug state: %v\n", settings.Debug)
			clientset, err := wf.GetClientset(settings)
			if err != nil {
				fmt.Fprintf(out, "Could not get Workflow Clientset: %s\n", err.Error())
				return
			}
			wflist, err := wf.ListWorkflows(clientset, settings)
			if err != nil {
				fmt.Fprintf(out, "Could not list workflows: %s\n", err.Error())
				return
			}
			printTable(out, wflist, settings)
		},
	}

	return workflowListCmd
}

// printTable pretty prints the list of workflows to out
func printTable(out io.Writer, wfList []v1alpha1.Workflow, settings *environment.Settings) {
	w := util.NewTabWriter(out)
	defer w.Flush()
	if settings.AllNamespaces {
		fmt.Fprint(w, "NAMESPACE\t")
	}
	fmt.Fprint(w, "NAME\tSTATUS\tAGE\tDURATION\tPRIORITY")
	fmt.Fprint(w, "\n")
	for _, wf := range wfList {
		ageStr := humanize.RelativeDurationShort(wf.ObjectMeta.CreationTimestamp.Time, util.Now())
		durationStr := humanize.RelativeDurationShort(wf.Status.StartedAt.Time, wf.Status.FinishedAt.Time)
		if settings.AllNamespaces {
			fmt.Fprintf(w, "%s\t", wf.ObjectMeta.Namespace)
		}
		var priority int
		if wf.Spec.Priority != nil {
			priority = int(*wf.Spec.Priority)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", wf.ObjectMeta.Name, workflowStatus(&wf), ageStr, durationStr, priority)
	}
}

// workflowStatus returns a human readable inferred workflow status based on workflow phase and conditions
func workflowStatus(wf *v1alpha1.Workflow) v1alpha1.NodePhase {
	switch wf.Status.Phase {
	case v1alpha1.NodeRunning:
		if wfutil.IsWorkflowSuspended(wf) {
			return "Running (Suspended)"
		}
		return wf.Status.Phase
	case v1alpha1.NodeFailed:
		if wfutil.IsWorkflowTerminated(wf) {
			return "Failed (Terminated)"
		}
		return wf.Status.Phase
	case "", v1alpha1.NodePending:
		if !wf.ObjectMeta.CreationTimestamp.IsZero() {
			return v1alpha1.NodePending
		}
		return "Unknown"
	default:
		return wf.Status.Phase
	}
}