## Deployment

### Cloud Run (Recommended for Quick Start)

**Why Cloud Run:**
- ✅ Serverless (no infrastructure management)
- ✅ Auto-scaling (0 to 1000+ instances)
- ✅ FedRAMP Moderate authorized (government/enterprise ready)
- ✅ Built-in HTTPS, load balancing, health checks
- ✅ Deploy in 3 commands

**Quick Deploy:**
```bash
# Use the included deploy script
./tools/deploy/cloud-run.sh apps/gateway-server

# Or manually:
gcloud builds submit --tag gcr.io/YOUR-PROJECT/gatewaystack
gcloud run deploy gatewaystack \
  --image gcr.io/YOUR-PROJECT/gatewaystack \
  --set-env-vars="OAUTH_ISSUER=https://your-tenant.auth0.com/"
```

**Cost:** ~$5-50/month depending on usage (generous free tier)

**See:** `docs/deployment/cloud-run.md` for full walkthrough

---

### Docker (Self-Hosted)

**Pre-built images:**
```bash
docker pull ghcr.io/davidcrowe/gatewaystack:latest
```

**Build yourself:**
```bash
# Gateway server
docker build -f apps/gateway-server/Dockerfile -t gatewaystack .

# Admin UI
docker build -f apps/admin-ui/Dockerfile -t gatewaystack-admin .
```

**Run locally:**
```bash
docker run -p 8080:8080 \
  -e OAUTH_ISSUER=https://your-tenant.auth0.com/ \
  -e OAUTH_AUDIENCE=https://gateway.local/api \
  gatewaystack
```

**See:** `docs/deployment/docker.md` for Docker Compose, Kubernetes manifests, etc.

---

### Other Platforms

| Platform | Difficulty | Guide |
|----------|------------|-------|
| **AWS ECS/Fargate** | Medium | `docs/deployment/aws.md` |
| **Azure Container Instances** | Medium | `docs/deployment/azure.md` |
| **Fly.io** | Easy | `docs/deployment/fly.md` |
| **Railway** | Easy | `docs/deployment/railway.md` |
| **Kubernetes** | Hard | `docs/deployment/kubernetes.md` |

**Air-gapped / on-prem deployments:** Fully supported (Docker + self-hosted)

---

### CI/CD

`.github/workflows/build.yml` builds the monorepo and runs `npm test` on every push and pull request to main.

**To add deployment:**
```yaml
# Add to build.yml after tests pass
- name: Deploy to Cloud Run
  if: github.ref == 'refs/heads/main'
  run: ./tools/deploy/cloud-run.sh apps/gateway-server
  env:
    GCP_PROJECT: ${{ secrets.GCP_PROJECT }}
```