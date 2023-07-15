import toml

with open('../../alire.toml', 'r') as tux_alire_toml_file:
    tux_alire_toml = toml.load(tux_alire_toml_file)

(tux_alire_toml["configuration"]["variables"])