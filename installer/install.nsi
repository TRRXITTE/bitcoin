OutFile "bitcoin-29.0-win64-setup.exe"
InstallDir "$PROGRAMFILES64\Bitcoin"
Section
  SetOutPath "$INSTDIR"
  File "release/bin/bitcoind.exe"
  File "release/bin/bitcoin-cli.exe"
  File "release/bin/bitcoin-tx.exe"
  File "release/bin/bitcoin-wallet.exe"
  File "release/bin/bitcoin-qt.exe"
SectionEnd
