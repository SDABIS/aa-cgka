usage() {
    echo "Usage: $0 [-c N] [-s] [-h]"
    echo "  -c   Init N client dockers"
    echo "  -s   Init Server"
    echo "  -h   Show help"
    exit 1
}

client_replicas=10
start_c=false
start_s=false

while getopts "c:sh" opt; do
    case "$opt" in
            c) 
                if [[ "$OPTARG" =~ ^[0-9]+$ ]]; then
                    client_replicas=$OPTARG
                    start_c=true
                else
                    echo "❌ Error: Introduce a valid number for option -c."
                    exit 1
                    usage
                fi
                ;;
            s) start_s=true ;;
            h) usage ;;
            *) usage ;;
    esac
done

if $start_c; then
    docker network create mls_network --driver overlay --scope swarm
    echo "Starting ${client_replicas} clients"
    REPLICAS=${client_replicas} docker stack deploy -c client/docker-compose.yml mls
fi

if $start_s; then
    echo "Starting server"
    cd ./server
    docker compose up -d 
fi

if ! $start_c && ! $start_s; then
    usage
fi