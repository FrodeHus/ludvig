import pprint
import socket
import tempfile
from typing import IO
import requests
from urllib3.connection import HTTPConnection
from urllib3.connectionpool import HTTPConnectionPool
from requests.adapters import HTTPAdapter


class DockerConnection(HTTPConnection):
    def __init__(self):
        super().__init__("localhost")

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("/var/run/docker.sock")


class DockerConnectionPool(HTTPConnectionPool):
    def __init__(self):
        super().__init__("localhost")

    def _new_conn(self):
        return DockerConnection()


class DockerAdapter(HTTPAdapter):
    def get_connection(self, url, proxies=None):
        return DockerConnectionPool()


class DockerClient:
    def __init__(self) -> None:
        self.__session = self.__get_docker_session()

    def get_version(self):
        data = self.__session.get("http://docker/version").json()
        return data["ApiVersion"]

    def get_image_list(self):
        image_list = self.__session.get("http://docker/images/json").json()
        for image in image_list:
            repo_tags = image["RepoTags"]
            pprint.pprint(repo_tags)

    def inspect_image(self, name: str):
        data = self.__session.get("http://docker/images/{}/json".format(name)).json()
        return data

    def image_history(self, name: str):
        data = self.__session.get("http://docker/images/{}/history".format(name)).json()
        return data

    def export_image(self, name: str) -> IO[bytes]:
        result = self.__session.get("http://docker/images/{}/get".format(name))
        fp = tempfile.TemporaryFile()
        fp.write(result.content)
        fp.flush()
        fp.seek(0)
        return fp

    def __get_docker_session(self) -> requests.Session:
        session = requests.Session()
        session.mount("http://docker", DockerAdapter())
        return session
