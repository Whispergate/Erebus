FROM itsafeaturemythic/mythic_python_base:1
RUN apt-get update && apt-get install python3 python3-pip python3-venv wget openssl mingw-w64 git --no-install-recommends -y

WORKDIR /Mythic/

RUN cd agent_code
RUN git clone https://github.com/mgeeky/PackMyPayload
RUN git clone https://github.com/mgeeky/ProtectMyTooling
RUN git clone https://github.com/Lavender-exe/Shellcrypt shellcrypt
RUN pip install -r shellcrypt/requirements.txt
RUN cd ../

RUN pip install -r requirements.txt

RUN ["python3", "main.py"]