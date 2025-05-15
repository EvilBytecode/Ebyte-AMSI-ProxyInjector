# Ebyte-ProxyInjector
A lightweight tool that injects a custom assembly proxy into a target process to silently bypass AMSI scanning by redirecting AmsiScanBuffer calls. It suspends the target’s threads, patches the function to always return AMSI_RESULT_CLEAN without altering original bytes directly, ensuring stealthy AMSI bypass.
