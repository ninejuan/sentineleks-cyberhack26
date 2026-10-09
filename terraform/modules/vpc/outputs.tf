output "vpc_id" {
  value = aws_vpc.main.id
}

output "vpc_cidr" {
  value = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "nat_gateway_id" {
  value = aws_nat_gateway.main.id
}

output "nat_public_ip" {
  description = "Egress IP of every private-subnet Lambda; allow-list it in MongoDB Atlas and ClickHouse Cloud"
  value       = aws_eip.nat.public_ip
}
