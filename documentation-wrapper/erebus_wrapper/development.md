+++
title = "Development"
chapter = false
weight = 15
pre = "<b>1. </b>"
+++

## High Level Flow chart

![High Level Flow Chart of Erebus' Workflow](/wrappers/erebus_wrapper/flow.png)

## Adding Features

### Modules
#### Module Tempalate
Folder Location: `erebus_wrapper/erebus/modules`

```python
import pefile, asyncio
#↬ Use async/await as done in the Mythic class
async def module_name(param1: str, param2: int, **param3: any) -> str:
    """Do something

    Args:
        param1 (str): Do something
        param2 (int): Do something
    
    Raises:
        Exception: Value Error
    
    Returns:
        str: Returns some string
    """
    try:
        addition = param1 + param2
    except ValueError:
        raise Exception("Incorrect Value")

    return addition    

if __name__ == "__main__": # <-- Test functionality by running the module alone before importing it
    addition = asyncio.run(module_name("number", 1))
    print(addition)
```

#### Agent Templates
Folder Location: `erebus_wrapper/agent_code/templates`
