provider "aws" {
  region  = "ap-south-1"
  profile = "harsh"
}

//key-pair

resource "tls_private_key" "task2_private_key" {
  algorithm   = "RSA"
  rsa_bits = 4096

}

resource "aws_key_pair" "task2_public_key" {
  key_name   = "task1_public_key"
  public_key = tls_private_key.task2_private_key.public_key_openssh
}


//security-group

resource "aws_security_group" "task2_SG" {
  name = "task2_SG"
  description = "Allow TCP inbound traffic"

  ingress {
    description = "SSH port from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP port from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
   ingress {
    description = "nfs port from VPC"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
 
  tags = {
    Name = "task2_SG"
  }
}


// aws-instance

resource "aws_instance" "task2_os" {
  ami             = "ami-0447a12f28fddb066"
  instance_type   = "t2.micro"
  security_groups =  ["task2_SG"] 
  key_name        = aws_key_pair.task2_public_key.key_name
  
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.task2_private_key.private_key_pem
    host     = aws_instance.task2_os.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd php git -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd"
    ]
  }

  tags = {
    Name = "task2_os"
  }
}


//efs
resource "aws_efs_file_system" "myefs" {
  creation_token   = "EFS Shared Data"
  performance_mode = "generalPurpose"
  encrypted = "true"

tags = {
    Name = "EFS Shared Data"
  }
}
resource "aws_efs_mount_target" "efs" {
  file_system_id  = "${aws_efs_file_system.myefs.id}"
  subnet_id       =  aws_instance.task2_os.subnet_id
  security_groups =  [aws_security_group.task2_SG.id]
}


//remote-execution

resource "null_resource" "remote-exec1" {
  
  depends_on = [
   aws_efs_mount_target.efs
  ]

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.task2_private_key.private_key_pem
    host     = aws_instance.task2_os.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo echo $(aws_efs_file_system.myefs.dns_name):  /var/www/html efs defaults,_netdev 0 0 >> /etc/fstab",
      "sudo mount echo $(aws_efs_file_system.myefs.dns_name):/  /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/Rishabh2000-bot/task.git /var/www/html"
    ]
  }
}


//bucket
resource "aws_s3_bucket" "me_bucket" {
  bucket = "rupe000"
  acl    = "private"

  tags = {
    Name = "bucket"
  }
}
resource "aws_s3_bucket_object" "object" {
  bucket = aws_s3_bucket.me_bucket.id
  key    = "ris"
  source = "C:/Users/Rishabh garg/Downloads/ris.jpg"
  acl = "public-read"
}


locals {
  s3_origin_id = "myS3Origin"
}


resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "bucket-origin-identity"
}

resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = "${aws_s3_bucket.me_bucket.bucket_regional_domain_name}"
    origin_id   = "${local.s3_origin_id}"
    s3_origin_config {
      origin_access_identity = "${aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path}"
    }
  }
    

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Some comment"


  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "blacklist"
      locations        = ["US", "CA"]
    }
  }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

data "aws_iam_policy_document" "s3_policy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.me_bucket.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }

  statement {
    actions   = ["s3:ListBucket"]
    resources = ["${aws_s3_bucket.me_bucket.arn}"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }
}

resource "aws_s3_bucket_policy" "bucket-policy" {
  bucket = aws_s3_bucket.me_bucket.id
  policy = data.aws_iam_policy_document.s3_policy.json
}



/*
//execute chrome

resource "null_resource" "local-exec1"  {
  depends_on = [
    aws_cloudfront_distribution.s3_distribution,
  ]

  provisioner "local-exec" {
    command = "chrome ${aws_instance.task2_os.public_ip}"
  }
}

*/

output "domain" {
  value = aws_cloudfront_distribution.s3_distribution.domain_name
}