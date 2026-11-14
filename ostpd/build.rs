// build.rs for ostpd
// Embeds a Windows manifest that requests Administrator privileges.
// This makes Windows show a UAC prompt when the binary is double-clicked
// or launched via ShellExecuteW("runas").

fn main() {
    // Key off the TARGET, not the host. In a build script `cfg(windows)`
    // describes the machine doing the building, so cross-compiling the helper
    // from Windows to Linux took this branch and failed with "Can only compile
    // resource file when target_env is gnu or msvc". CARGO_CFG_TARGET_OS is the
    // target being built for, which is what actually decides whether a Windows
    // manifest belongs in the binary.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }
    // Second gate, on the HOST: winres is declared under
    // [target.'cfg(windows)'.build-dependencies], and build-dependencies are
    // resolved against the host triple, so the crate simply does not exist when
    // building on Linux. Referencing it unconditionally would fail to compile
    // there even though the target check above already passed.
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_manifest(r#"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
    <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
        <security>
            <requestedPrivileges>
                <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
            </requestedPrivileges>
        </security>
    </trustInfo>
    <dependency>
        <dependentAssembly>
            <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls"
                version="6.0.0.0" processorArchitecture="*"
                publicKeyToken="6595b64144ccf1df" language="*"/>
        </dependentAssembly>
    </dependency>
</assembly>
"#);
        res.compile().expect("failed to compile Windows resources");
    }
}
