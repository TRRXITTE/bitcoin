OutFile "bitcoin-29.0-win64-setup-unsigned.exe"
InstallDir "$PROGRAMFILES64\Bitcoin"
Section
  SetOutPath "$INSTDIR"
  File "unsigned/bin/bitcoind.exe"
  File "unsigned/bin/bitcoin-cli.exe"
  File "unsigned/bin/bitcoin-tx.exe"
  File "unsigned/bin/bitcoin-wallet.exe"
  File "unsigned/bin/bitcoin-qt.exe"
SectionEnd
