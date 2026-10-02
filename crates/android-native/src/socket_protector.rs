use std::{net::UdpSocket, os::fd::AsRawFd};

use anyhow::{anyhow, Result};
use jni::{
    objects::{GlobalRef, JObject, JValue},
    JNIEnv, JavaVM,
};

pub(crate) struct SocketProtector {
    vm: JavaVM,
    service: Option<GlobalRef>,
}

impl SocketProtector {
    pub(crate) fn connection_cancelled(&self, generation: i64) -> Result<bool> {
        let mut env = self.vm.attach_current_thread()?;
        let service = self
            .service
            .as_ref()
            .ok_or_else(|| anyhow!("VPN service reference is unavailable"))?;
        Ok(env
            .call_method(
                service.as_obj(),
                "isConnectionCancelled",
                "(J)Z",
                &[JValue::Long(generation)],
            )?
            .z()?)
    }

    pub(crate) fn new(env: &JNIEnv<'_>, service: &JObject<'_>) -> Result<Self> {
        Ok(Self {
            vm: env.get_java_vm()?,
            service: Some(env.new_global_ref(service)?),
        })
    }

    pub(crate) fn protect(&self, socket: &UdpSocket) -> Result<()> {
        let mut env = self.vm.attach_current_thread()?;
        let service = self
            .service
            .as_ref()
            .ok_or_else(|| anyhow!("VPN service reference is unavailable"))?;
        let protected = env
            .call_method(
                service.as_obj(),
                "protectAndBindSocket",
                "(I)Z",
                &[JValue::Int(socket.as_raw_fd())],
            )?
            .z()?;
        if protected {
            Ok(())
        } else {
            Err(anyhow!("Android refused to protect or bind the UDP socket"))
        }
    }
}

impl Drop for SocketProtector {
    fn drop(&mut self) {
        if let Ok(_environment) = self.vm.attach_current_thread() {
            drop(self.service.take());
        }
    }
}
