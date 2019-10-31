# QQProtect UDP Inspector

A tool to reveal UDP packets sent by `QQProtect.exe`.

## Compile

```console
$ msbuild QQProtectUdpInspector.sln /p:Configuration=Release /p:Platform=x64    # or `x86`. It is based on your system platform.
```

## Usage

After compilation, Just run 

```
$ .\bin\x64-Release\QQProtectUdpInspector.exe   # or `.\bin\x86-Release\QQProtectUdpInspector.exe`
```

with Administrator privilege.

## Screen record

![](ScreenRecord.gif)

