import logging
from server import Server

logging.basicConfig(level='DEBUG')


def main():
    Server().start()


if __name__ == '__main__':
    main()
