$ErrorActionPreference='Continue'
$img='x10lab/github-actions-runner-toolchains:win2022-rust'
& docker volume create shepherd-target | Out-Null
$inner = @'
$ErrorActionPreference='Continue'
Write-Output "=== cargo test --workspace --no-fail-fast (excluding the 3 crates that cannot COMPILE) ==="
& cargo test --workspace --no-fail-fast --exclude shepherd-daemon --exclude shepherd-bench --exclude shepherd-tier
Write-Output "TEST_EXIT=$LASTEXITCODE"
'@
$inner | Out-File -Encoding ascii C:\Windows\Temp\inbuild5.ps1
& docker run --rm --entrypoint powershell -v C:\shepherd-ci:C:\src -v C:\Windows\Temp:C:\host -v shepherd-target:C:\t -w C:\src `
  -e CARGO_TARGET_DIR=C:\t -e CARGO_TERM_COLOR=never -e RUST_BACKTRACE=1 `
  $img -ExecutionPolicy Bypass -File C:\host\inbuild5.ps1 2>&1 | Tee-Object -FilePath C:\shepherd-log\build5.log
Write-Output "DOCKER_EXIT=$LASTEXITCODE"
