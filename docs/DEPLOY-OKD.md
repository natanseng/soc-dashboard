# Deploy — OKD (OpenShift)

Guia para deployar a dashboard em um cluster OKD (OpenShift Kubernetes Distribution) auto-hospedado.

## Pré-requisitos

- Cluster OKD 4.10+
- `oc` CLI configurado com acesso ao cluster
- Imagens do backend e frontend já buildadas e em um registry acessível
- PostgreSQL e Redis disponíveis (gerenciados ou auto-hospedados)

## Arquitetura

```
OKD Cluster
├── Namespace: soc-dashboard
│   ├── Pod: api-<hash>
│   │   ├── FastAPI (port 8000)
│   │   └── Static files
│   ├── Pod: collector-<hash>
│   │   └── APScheduler
│   ├── Service: api-svc (port 8000, ClusterIP)
│   └── Route: dashboard.seu-dominio.local
├── StatefulSet: postgres (ou gerenciado fora)
└── StatefulSet: redis (ou gerenciado fora)
```

## Passo 1: Criar namespace

```bash
oc create namespace soc-dashboard
oc project soc-dashboard
```

## Passo 2: Criar secrets

### Secret da API do Vision One

```bash
oc create secret generic vision-one \
  --from-literal=token=seu_token_aqui \
  --from-literal=base-url=https://api.xdr.trendmicro.com
```

### Secret do banco de dados (se necessário)

```bash
oc create secret generic db-credentials \
  --from-literal=username=socdash \
  --from-literal=password=senha_segura \
  --from-literal=host=postgres.seu-namespace.svc.cluster.local \
  --from-literal=port=5432 \
  --from-literal=dbname=socdash
```

### Secret do Redis (se necessário)

```bash
oc create secret generic redis-credentials \
  --from-literal=url=redis://redis:6379/0
```

## Passo 3: ConfigMap para o .env

```bash
cat > /tmp/config-env << 'EOF'
V1_API_BASE=https://api.xdr.trendmicro.com
TENANT=salvador
REDIS_URL=redis://redis:6379/0
DB_DSN=postgresql://socdash:senha_segura@postgres:5432/socdash
TIER1_INTERVAL=60
TIER2_INTERVAL=300
TIER3_INTERVAL=900
TIER4_INTERVAL=3600
GEOIP_DB=
EOF

oc create configmap dashboard-config --from-file=/tmp/config-env
```

## Passo 4: Deployments

Crie um arquivo `deployment.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: api-svc
  namespace: soc-dashboard
spec:
  selector:
    app: api
  ports:
    - port: 8000
      targetPort: 8000
  type: ClusterIP
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: soc-dashboard
spec:
  replicas: 2
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
      - name: api
        image: seu-registry/soc-dashboard:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 8000
        env:
        - name: V1_API_TOKEN
          valueFrom:
            secretKeyRef:
              name: vision-one
              key: token
        - name: V1_API_BASE
          valueFrom:
            secretKeyRef:
              name: vision-one
              key: base-url
        - name: TENANT
          value: salvador
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: redis-credentials
              key: url
        - name: DB_DSN
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: dsn
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /healthz
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            cpu: 100m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 1Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: collector
  namespace: soc-dashboard
spec:
  replicas: 1
  selector:
    matchLabels:
      app: collector
  template:
    metadata:
      labels:
        app: collector
    spec:
      containers:
      - name: collector
        image: seu-registry/soc-dashboard:latest
        imagePullPolicy: Always
        command: ["python", "-m", "collectors.run"]
        env:
        - name: V1_API_TOKEN
          valueFrom:
            secretKeyRef:
              name: vision-one
              key: token
        - name: V1_API_BASE
          valueFrom:
            secretKeyRef:
              name: vision-one
              key: base-url
        - name: TENANT
          value: salvador
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: redis-credentials
              key: url
        - name: DB_DSN
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: dsn
        resources:
          requests:
            cpu: 200m
            memory: 512Mi
          limits:
            cpu: 1000m
            memory: 2Gi
```

Applique:

```bash
oc apply -f deployment.yaml
```

## Passo 5: Route (acesso externo)

```bash
oc create route edge dashboard \
  --service=api-svc \
  --insecure-policy=Redirect \
  --hostname=dashboard.seu-dominio.local
```

Verifique:

```bash
oc get routes
```

Acesse em `https://dashboard.seu-dominio.local`.

## Passo 6: Verificação

### Pod status

```bash
oc get pods -n soc-dashboard
oc logs -f deployment/api
oc logs -f deployment/collector
```

### Health check

```bash
oc port-forward svc/api-svc 8000:8000 &
curl http://localhost:8000/healthz
```

### Snapshot da dashboard

```bash
curl https://dashboard.seu-dominio.local/api/salvador/overview
```

## Scaling

### Aumentar replicas da API

```bash
oc scale deployment/api --replicas=3
```

### Monitorar consumo de recursos

```bash
oc top pods -n soc-dashboard
oc top nodes
```

## Troubleshooting

### Pod não sobe

```bash
oc describe pod <pod-name>
oc logs <pod-name>
```

### ImagePullBackOff

Verifique se o registry é acessível e as credenciais estão corretas:

```bash
oc create secret docker-registry regcred \
  --docker-server=seu-registry \
  --docker-username=usuario \
  --docker-password=senha
oc set serviceaccount default regcred
```

### Health check falha

Verifique logs do API:

```bash
oc logs deployment/api --tail=50
```

Confirme que Redis e PostgreSQL estão acessíveis:

```bash
oc rsh deployment/api
redis-cli -u $REDIS_URL ping
psql $DB_DSN -c "SELECT 1"
```

### Desempenho lento

Verifique limits de recursos:

```bash
oc top pods
```

Se acima dos limits, aumente em `deployment.yaml`:

```yaml
resources:
  limits:
    cpu: 2000m
    memory: 4Gi
```

## Backup e Restore

### Backup de dados (Redis)

```bash
oc exec redis-0 -- redis-cli BGSAVE
oc cp soc-dashboard/redis-0:/data/dump.rdb ./dump.rdb
```

### Backup do banco (PostgreSQL)

```bash
oc exec postgres-0 -- pg_dump -U socdash socdash > backup.sql
```

## Remoção

Para deletar o deployment:

```bash
oc delete namespace soc-dashboard
```

Isso remove todos os recursos (pods, services, routes, secrets, configmaps).

## Próximos passos

- Para produção em **AL2023 ou RHEL9**, veja `DEPLOY-AL2023.md` ou `DEPLOY-RHEL9.md`
- Para **Docker Compose** em dev, veja `DEPLOY-DOCKER-COMPOSE.md`
- Para **Kubernetes genérico**, veja `DEPLOY-KUBERNETES.md` (em breve)
- Para **monitoramento**, veja `MONITORING.md` (em breve)
