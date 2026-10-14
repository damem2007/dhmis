from pydantic import BaseModel


# Defines the throttle args model, contract, or value object.
class ThrottleArgs(BaseModel):
    limit: int
    seconds: int

#defined throttle limit and seconds for the back office app. It would be parsed from the system set up/configuration later on
#This is to be used for all the back office throttle
# Retrieve get bo throttle args for the current request or workflow.
def get_bo_throttle_args() -> ThrottleArgs:
    return ThrottleArgs(limit=8, seconds=300)

#defined throttle limit and seconds for the front office/public app. It would be parsed from the system set up/configuration later on
#This is to be used for all the cms throttle
# Retrieve get fo throttle args for the current request or workflow.
def get_fo_throttle_args() -> ThrottleArgs:
    return ThrottleArgs(limit=5, seconds=300)

#defined throttle limit and seconds for the patient app. It would be parsed from the system set up/configuration later on
#This is to be used for all the patient portal throttle
# Retrieve get pt throttle args for the current request or workflow.
def get_pt_throttle_args() -> ThrottleArgs:
    return ThrottleArgs(limit=6, seconds=300)
