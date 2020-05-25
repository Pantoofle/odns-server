import argparse

from ecies.utils import generate_key


def gen_keys(secret_path, public_path):
    print("Generating the secret key...")
    secret_key = generate_key()
    public_key = secret_key.public_key

    print(f"Writing the secret key {secret_path}")
    with open(secret_path, 'wb+') as f:
        f.write(secret_key.to_pem())

    print(f"Writing the public key {public_path}")
    with open(public_path, 'w+') as f:
        f.write(public_key.format(True).hex())


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Utils for ODNS server deployment")
    p.add_argument("--generate", "-g", action='store_true', default=False,
                   help="Generates a new key pair")
    p.add_argument("--secret", "-s", default="./secret.pem",
                   metavar="<secret>",
                   help="Export name of the secret key")
    p.add_argument("--public", "-p", default="./public.hex",
                   metavar="<public>",
                   help="Export name of the public key")
    args = p.parse_args()

    if args.generate:
        gen_keys(args.secret, args.public)
