FROM itsafeaturemythic/mythic_python_base:latest
RUN apt-get update && apt-get install python3 python3-pip python3-venv wget openssl mingw-w64 --no-install-recommends -y

WORKDIR /Mythic/

RUN pip install mythic-container
RUN pip install win32con win32api

RUN ["python3", "main.py"]