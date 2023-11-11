from crypto.dhke import dhke

peer_value = bytes.fromhex('79d756bbc5a0d69634141ba4327d547e91da42c84590855ea0308e0ca6baaa16')
print(len(peer_value))
x = dhke.generate_keys(peer_value)
print(x)

