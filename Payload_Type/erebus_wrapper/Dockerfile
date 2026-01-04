FROM itsafeaturemythic/mythic_python_base:latest
RUN apt-get update && apt-get install python3 python3-pip python3-venv wget openssl mingw-w64 git msitools cmake ninja make --no-install-recommends -y

WORKDIR /Mythic/

COPY [".", "."]

# RUN python3 -m venv /venv

# RUN /venv/bin/python -m pip install -r requirements.txt
RUN pip3 install -r requirements.txt --break-system-packages

CMD ["python3", "main.py"]