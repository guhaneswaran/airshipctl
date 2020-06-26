## airshipctl cluster

Manage Kubernetes clusters

### Synopsis

This command provides capabilities for interacting with a Kubernetes cluster,
such as getting status and deploying initial infrastructure.


### Options

```
  -h, --help   help for cluster
```

### Options inherited from parent commands

```
      --airshipconf string   Path to file for airshipctl configuration. (default "$HOME/.airship/config")
      --debug                enable verbose output
      --kubeconfig string    Path to kubeconfig associated with airshipctl configuration. (default "$HOME/.airship/kubeconfig")
```

### SEE ALSO

* [airshipctl](airshipctl.md)	 - A unified entrypoint to various airship components
* [airshipctl cluster init](airshipctl_cluster_init.md)	 - Deploy cluster-api provider components
* [airshipctl cluster move](airshipctl_cluster_move.md)	 - Move Cluster API objects, provider specific objects and all dependencies to the target cluster
* [airshipctl cluster renew-certs](airshipctl_cluster_renew-certs.md)	 - Renew control plane certificates close to expiration and restart control plane components
* [airshipctl cluster status](airshipctl_cluster_status.md)	 - Retrieve statuses of deployed cluster components

