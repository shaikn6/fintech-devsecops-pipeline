#!/bin/bash
set -o xtrace

# Bootstrap script for EKS worker nodes (${environment} / ${cluster_name})
# Runs the standard Amazon EKS-optimized AMI bootstrap against this cluster.

/etc/eks/bootstrap.sh ${cluster_name} \
  --kubelet-extra-args '--node-labels=environment=${environment}'
