FROM python:3.8-slim-buster
WORKDIR /flask
COPY ts.py /flask
COPY requirements.txt /flask
RUN apt update -y \
&& apt install build-essential -y \
&& apt install cmake -y \
&& apt install libpng-dev -y \
&& apt install libgl1 -y \
&& apt install libglib2.0-0 -y \
&& apt install openssh-client -y
RUN pip3 install -r requirements.txt
ENV FLASK_RUN_HOST=0.0.0.0
EXPOSE 5000
#generate open ssl key in the entrypoint
ENTRYPOINT [ "flask", "--app" , "ts", "run" ]