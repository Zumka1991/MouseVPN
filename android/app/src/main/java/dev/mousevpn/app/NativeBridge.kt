package dev.mousevpn.app

object NativeBridge {
    init {
        System.loadLibrary("mousevpn_android")
    }

    external fun generateDeviceKeys(): String

    external fun prepare(
        service: MouseVpnService,
        endpoint: String,
        serverPublicKey: String,
        clientPrivateKey: String,
        protocol: String,
        generation: Long,
    ): String

    external fun start(handle: Long, tunFd: Int): Boolean
    external fun networkChanged(handle: Long)
    external fun stop(handle: Long)
    external fun status(handle: Long): String
    external fun metrics(handle: Long): String
}
