FROM itsafeaturemythic/mythic_python_base:latest
RUN apt-get clean
RUN apt-get update && apt-get install python3 python3-pip python3-venv wget openssl mingw-w64 git msitools make p7zip-full zip wixl osslsigncode --no-install-recommends -y

WORKDIR /Mythic/

COPY [".", "."]

RUN pip3 install -r requirements.txt --break-system-packages

CMD ["python3", "main.py"]