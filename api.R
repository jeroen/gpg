# Local keys
gpg_key_list(private_only = FALSE)
gpg_key_gen(size, name, email, expiration = NULL, comment = "", password = readline)
gpg_key_import(data, ascii_armored = TRUE)
gpg_key_delete(id)
gpg_key_export(id, ascii_armored = TRUE)

# Key server
gpg_key_search(filter)
gpg_key_receive(id)
gpg_key_publish(id, confirm = interactive())

# Authenticate
gpg_sign(message, id = gpg_options("default-key"), password = readline)
gpg_verify(message, sigfile)

# Encrypt
gpg_encrypt(message, con =, id = gpg_options("default-key"))
gpg_decrypt(ciphertext, password = readline)
