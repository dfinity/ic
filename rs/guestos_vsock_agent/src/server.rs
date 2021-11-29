// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Code based on:
// https://github.com/aws/aws-nitro-enclaves-acm/blob/main/src/vtok_rpc/src/proto.rs

use crate::{VsockAddr, VsockStream};
use std::io;
use std::mem::size_of;
use std::os::unix::io::{FromRawFd, RawFd};

/// An AF_VSOCK listener (server)
#[derive(Debug, Clone)]
pub struct VsockListener {
    fd: RawFd,
}

impl VsockListener {
    /// Create and return a VsockListener that is bound to `addr` and ready to
    /// accept client connections.
    pub fn bind(addr: VsockAddr, backlog: std::os::raw::c_int) -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut sa = libc::sockaddr_vm {
            svm_family: libc::AF_VSOCK as libc::sa_family_t,
            svm_cid: addr.cid,
            svm_port: addr.port,
            svm_reserved1: 0,
            svm_zero: [0u8; 4],
        };
        let mut rc = unsafe {
            libc::bind(
                fd,
                &mut sa as *mut _ as *mut libc::sockaddr,
                size_of::<libc::sockaddr_vm>() as u32,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        rc = unsafe { libc::listen(fd, backlog) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        Ok(Self { fd })
    }

    /// Accept a client connection and return a client stream
    pub fn accept(&self) -> io::Result<VsockStream> {
        let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        let mut addr_len = size_of::<libc::sockaddr_vm>() as libc::socklen_t;
        let cl_fd = unsafe {
            libc::accept(
                self.fd,
                &mut addr as *mut _ as *mut libc::sockaddr,
                &mut addr_len,
            )
        };
        if cl_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(unsafe { VsockStream::from_raw_fd(cl_fd) })
    }
}

impl Drop for VsockListener {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}
