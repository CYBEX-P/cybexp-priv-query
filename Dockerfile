FROM cybexp-priv-libs

# setup environment & install dependencies
COPY ./requirements.txt /query/requirements.txt
RUN pip3 install -r /query/requirements.txt

# misc
RUN mkdir -p /secrets


# copy query,config last
COPY ./query /query
COPY ./config.yaml /query/config.yaml


WORKDIR /query
