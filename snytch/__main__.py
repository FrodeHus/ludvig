import sys

from snytch.image_scanner import SecretsScanner


def main():
    scanner = SecretsScanner(sys.argv[1])
    scanner.scan()


if __name__ == "__main__":
    main()
