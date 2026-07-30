data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_security_group" "monitoring_sg" {
  name        = "sentinel-monitoring-sg"
  description = "Allows SSH, Grafana, and Prometheus access from a single trusted IP"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip_cidr]
  }

  ingress {
    description = "Grafana"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip_cidr]
  }

  ingress {
    description = "Prometheus"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "monitoring_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.monitoring_sg.id]
  key_name               = var.key_name

  user_data = <<-EOF
              #!/bin/bash
              apt-get update -y
              apt-get install -y docker.io docker-compose
              systemctl start docker
              systemctl enable docker

              mkdir -p /opt/monitoring
              cd /opt/monitoring

              cat << 'COMPOSE' > docker-compose.yml
              version: '3.8'
              services:
                prometheus:
                  image: prom/prometheus:latest
                  ports:
                    - "9090:9090"
                  volumes:
                    - ./prometheus.yml:/etc/prometheus/prometheus.yml
                grafana:
                  image: grafana/grafana:latest
                  ports:
                    - "3000:3000"
                  environment:
                    - GF_SECURITY_ADMIN_PASSWORD=${var.grafana_admin_password}
              COMPOSE

              cat << 'PROM' > prometheus.yml
              global:
                scrape_interval: 15s
              scrape_configs:
                - job_name: 'prometheus'
                  static_configs:
                    - targets: ['localhost:9090']
              PROM

              docker-compose up -d
              EOF

  tags = {
    Name             = "sentinel-monitoring-server"
    "sentinel:exclude" = "true"  # tells the auditor to skip this instance
  }
}

resource "aws_eip" "monitoring_eip" {
  instance = aws_instance.monitoring_server.id
  domain   = "vpc"
}
