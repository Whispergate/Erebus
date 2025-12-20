FROM itsafeaturemythic/mythic_python_base:latest
RUN apt-get update && apt-get install python3 python3-pip python3-venv wget openssl mingw-w64 git --no-install-recommends -y

copy requirements.txt /
RUN pip install -r /requirements.txt

WORKDIR /Mythic/

RUN ["python3", "main.py"]