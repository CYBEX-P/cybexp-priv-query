#!/usr/bin/env bash

DIR_PATH=`dirname $0`
FULL_PATH=`readlink --canonicalize $DIR_PATH`

IMAGE_NAME=cybexp-priv-query

DOCKERFILE_LOC=$FULL_PATH

OG_ARGUMENTS="$@" # in case we need to exec when starting docker

ALLOWED_QUERY_TYPES=('search' 'count')


if [ "`id -u`" -eq "0" ]; then
   echo "Not recomended to run as root. Continuing anyways..."
fi
if [[ "`groups`" == *"docker"* || "`id -u`" -eq "0" ]]; then
      DOCKER="docker"
   else
      DOCKER="sudo docker"

fi

function print_help {
   echo
   echo 'Create and run a docker container to query the encrypted backend. By default the container is left behind,'
   echo 'vacuum recomended. Build at least once or when code has changed.'
   echo
   echo -e 'Usage:'
   echo -e "  $0"' [Options] config-file query output-file'
   echo -e "  $0"' --build --build-only'
   echo 
   echo -e 'Positional arguments:'
   echo -e '  config-file\t\tconfiguration file yaml'
   echo -e '  query\t\t\tstring representing any query value'
   echo -e '  output-file\t\tfile where the unencrypted information is placed'
   echo
   echo -e 'Options arguments:'
   echo -e '  -b, --build\t\tbuild docker image'
   echo -e '  --build-only\t\texit after building'
   echo -e '  -s, --shell\t\trun shell (mostly for debugging), ignores most flags'

   echo -e '  -q, --query-type TYPE\tChange query type, TYPE must be one of'
   echo -e "                       \tthe following: ${ALLOWED_QUERY_TYPES[*]}. (default: search)"

   echo -e '  -f, --from-time EPOCH\tinteger epoch used as > filter for the query'
   echo -e '  -t, --to-time EPOCH\tinteger epoch used as < filter for the query'

   echo -e '  -l, --left-inclusive\tmodify the --from-time to be inclusive >='
   echo -e '  -r, --right-inclusive\tmodify the --to-time to be inclusive <='

   echo -e '  -c, --vacuum\t\tremove container upon exit. If more than one container'
   echo -e '              \t\tof this type exists, it will remove all'

   echo -e '  -h, --help\t\tprint this help'


   echo 
}

function build_image {
  $DOCKER build -t $IMAGE_NAME $DOCKERFILE_LOC
  return $?
}

function run_image {
   other_args="$QUERY --query-type $QUERY_TYPE"
   # touch $OUTPUT_FILE
   if [ $LEFT_INCLUSIVE -eq 1 ]; then
      other_args="$other_args --left-inclusive"
   fi
   if [ $RIGHT_INCLUSIVE -eq 1 ]; then
      other_args="$other_args --right-inclusive"
   fi

   if [ -n "${FROM_TIME+set}" ]; then
      other_args="$other_args --from-time $FROM_TIME"
   fi
   if [ -n "${TO_TIME+set}" ]; then
      other_args="$other_args --to-time $TO_TIME"
   fi
   echo "config file: $CONFIG_FILE"
   CONT_ID=$($DOCKER run -d -v `realpath $CONFIG_FILE`:/config.yaml -v $FULL_PATH/secrets:/secrets/ -it $IMAGE_NAME $other_args)
   $DOCKER logs -f $CONT_ID
   $DOCKER cp $CONT_ID:/output `realpath $OUTPUT_FILE`   > /dev/null 2>&1 # supress output
   sudo chown $USER:$USER `realpath $OUTPUT_FILE` > /dev/null 2>&1 # supress output
   return $?
}
function run_shell {
   touch $OUTPUT_FILE
   $DOCKER run  -v `realpath $CONFIG_FILE`:/config.yaml -v $FULL_PATH/secrets:/secrets/ --entrypoint /bin/bash -it $IMAGE_NAME
   CONT_ID=`$DOCKER ps --all | grep $IMAGE_NAME | awk '{print $1}' | head -n 1`
   $DOCKER cp $CONT_ID:/output `realpath $OUTPUT_FILE` > /dev/null 2>&1 # supress output
   sudo chown $USER:$USER `realpath $OUTPUT_FILE` > /dev/null 2>&1 # supress output

   return $?

}
function remove_container {
   DOCKER_ID=`$DOCKER ps --all | grep $IMAGE_NAME | awk '{print $1}'`
   echo "Stopping and removing container(s)"
   $DOCKER stop $DOCKER_ID > /dev/null 2>&1
   $DOCKER rm $DOCKER_ID #> /dev/null 2>&1
   return $?
}

#flags
BUILD_IT=0
BUILD_ONLY=0
SHELL_ONLY=0
CLEANUP=0
LEFT_INCLUSIVE=0
RIGHT_INCLUSIVE=0
QUERY_TYPE=search

POSITIONAL=""
while (( "$#" )); do
   case "$1" in
      -h|--help)
         print_help
         exit 0
         ;;
      -b|--build)
         BUILD_IT=1
         shift
         ;;
      --build-only)
         BUILD_ONLY=1
         shift
         ;;
      -s|--shell)
         SHELL_ONLY=1
         shift
         ;;

      -c|--vacuum)
         CLEANUP=1
         shift
         ;;
      -l|--left-inclusive)
         LEFT_INCLUSIVE=1
         shift
         ;;

      -r|--right-inclusive)
         RIGHT_INCLUSIVE=1
         shift
         ;;
      -f|--from-time)
         if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
            FROM_TIME=$2
            shift 2
         else
            echo "Error: Argument for $1 is missing" >&2
            print_help
            exit 1
         fi
         ;;
      -t|--to-time)
         if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
            TO_TIME=$2
            shift 2
         else
            echo "Error: Argument for $1 is missing" >&2
            print_help
            exit 1
         fi
         ;;
      -q|--query-type)
         if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
            QUERY_TYPE=$2
            if [[ " ${ALLOWED_QUERY_TYPES[*]} " != *"$QUERY_TYPE"* ]]; then
                echo "argument -q/--query-type: invalid choice: '$QUERY_TYPE' (choose from: ${ALLOWED_QUERY_TYPES[*]})"
                exit 1
            fi
            shift 2
         else
            echo "Error: Argument for $1 is missing" >&2
            print_help
            exit 1
         fi
         ;;
      -*|--*=) # unsupported flags
         echo "Error: Unsupported flag $1" >&2
         exit 1
         ;;
      *) # preserve positional arguments
         POSITIONAL="$POSITIONAL $1"
         shift
         ;;
   esac
done
# set positional arguments in their proper place
eval set -- "$POSITIONAL"
if [ "$#" -eq 3 ]&& [ $BUILD_ONLY -eq 0 ]; then
   CONFIG_FILE="$1"
   QUERY="$2"
   OUTPUT_FILE="$3"
   shift 3
elif [ $BUILD_ONLY -eq 0 ];then
   # echo $#
   # echo $POSITIONAL
   echo "Error: Missing positional arguments." >&2
   print_help
   exit 2
fi

DOCKER_STATE=`systemctl status docker | grep Active: | head -n 1 | awk '{print $2}'`

if [ "$DOCKER_STATE" = "inactive" ]; then
   echo "Starting docker service..."
   sudo systemctl start docker
   exec $0 $OG_ARGUMENTS
fi

if [ $BUILD_IT -eq 1 ]; then
   build_image
   if [ $? -ne 0 ]; then
      echo "Error: Failed to build image" >&2
      exit 3
   fi
fi
if [ $BUILD_ONLY -eq 1 ]; then
   exit 0
fi


if [ "$DOCKER_STATE" = "active" ]; then
   if [ $SHELL_ONLY -eq 1 ]; then
      run_shell
   else
      run_image
   fi

   if [ $CLEANUP -eq 1 ]; then
      remove_container
   fi

else
   echo 'Failed to start docker, please start it.' >&2
   exit 1
fi





# parse yaml file 
# https://stackoverflow.com/a/21189044/12044480
