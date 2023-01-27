import tarfile
from typing import IO, List
from ._docker._definitions import Image, LayerFile
from ._providers import BaseFileProvider
from ._docker._main import read_local_docker_image
from knack.log import get_logger

logger = get_logger(__name__)


class ContainerProvider(BaseFileProvider):
    def __init__(
        self,
        repository: str,
        include_first_layer=False,
        exclusions: List[str] = None,
        max_file_size=10000,
    ) -> None:
        super().__init__(exclusions=exclusions, max_file_size=max_file_size)
        self.repository = repository
        self.include_first_layer = include_first_layer

    def get_files(self):
        with self.__get_image() as image:
            layers = image.layers[1:] if not self.include_first_layer else image.layers
            for layer in [l for l in layers if not l.empty_layer]:
                logger.info("layer %s: %s", layer.id, layer.created_by)
                with image.image_archive.extractfile(
                    "{}/layer.tar".format(layer.id)
                ) as layer_archive:
                    with tarfile.open(fileobj=layer_archive, mode="r") as lf:
                        try:
                            for member in lf.getmembers():
                                if (
                                    self.is_excluded(member.name)
                                    or not member.isfile
                                    or member.size > self.max_file_size
                                ):
                                    continue

                                file_data = self.__extract_file(lf, member)
                                if not file_data:
                                    continue
                                with LayerFile(file_data) as file_data:
                                    if not file_data:
                                        continue
                                    yield file_data, member.name, layer.id, layer.created_by
                        except tarfile.ReadError:
                            logger.error("failed to read files from layer %s", layer.id)

    def __get_image(self) -> Image:
        return read_local_docker_image(self.repository)

    def __extract_file(
        self, image: tarfile.TarFile, file: tarfile.TarInfo
    ) -> IO[bytes]:
        if file.isfile():
            return image.extractfile(file)
        return None
