import asyncio


async def hello_world() -> str:
    return "Hi from test func"


def sync_func() -> str:
    # run the async function
    # return asyncio.run(hello_world())
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(hello_world())

if __name__ == "__main__":
    print(sync_func())
