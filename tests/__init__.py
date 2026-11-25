import logging

# Keep test output readable: the service logs every state change.
logging.getLogger("scapegoat").addHandler(logging.NullHandler())
logging.getLogger("scapegoat").propagate = False
