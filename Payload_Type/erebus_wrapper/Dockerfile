FROM itsafeaturemythic/mythic_python_dotnet:latest
RUN apt-get clean
RUN apt-get update && apt-get install python3 python3-pip python3-venv wget openssl mingw-w64 git msitools msiextract wixl make p7zip-full zip osslsigncode --no-install-recommends -y

WORKDIR /Mythic/

COPY [".", "."]

RUN pip3 install -r requirements.txt --break-system-packages

CMD ["python3", "main.py"]