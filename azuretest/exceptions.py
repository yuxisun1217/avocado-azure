
class SkipCaseError(Exception):
    def __init__(self, err="Skip this case."):
        Exception.__init__(self, err)


class VMCreateError(Exception):
    def __init__(self, err="VM create failed."):
        Exception.__init__(self, err)


# waagent service exceptions
class WaagentServiceError(Exception):
    def __init__(self, err="waagent service status error"):
        Exception.__init__(self, err)


class WaagentStopError(WaagentServiceError):
    def __init__(self, err="Error when stopping waagent service"):
        WaagentServiceError.__init__(self, err)


class WaagentStartError(WaagentServiceError):
    def __init__(self, err="Error when starting waagent service"):
        WaagentServiceError.__init__(self, err)
