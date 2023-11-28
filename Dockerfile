# Build stage: compile Python dependencies
FROM ubuntu:focal as builder
ENV PIP_ROOT_USER_ACTION=ignore
COPY requirements.txt ./
RUN apt-get update -y && apt-get upgrade -y
RUN apt-get install -y python3 pip
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --user -r requirements.txt

# Final stage: copy over Python dependencies and install production Node dependencies
FROM ubuntu:focal
LABEL "network.forta.settings.agent-logs.enable"="true"
ENV PIP_ROOT_USER_ACTION=ignore
ENV PATH=/root/.local:$PATH
ENV NODE_ENV=production
WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY ./src ./src
COPY package*.json ./
COPY LICENSE.md ./
# update & install node
RUN apt-get update -y && apt-get upgrade -y
RUN apt-get -y install curl gnupg
RUN curl -sL https://deb.nodesource.com/setup_14.x  | bash -
RUN apt-get -y install nodejs
# this python version should match the build stage python version
RUN apt-get install -y python3 pip
RUN python3 -m pip install --upgrade pip
RUN npm ci --production
CMD [ "npm", "run", "start:prod" ]
