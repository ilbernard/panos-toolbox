import logging


def get_logger(name, verbose=False):
    logging.basicConfig(format="%(levelname)s %(name)s: %(message)s")
    log = logging.getLogger(name)
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    return log
