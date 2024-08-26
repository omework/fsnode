# fsnode

`fsnode` is a Content Delivery Network (CDN) service designed to enhance the distribution and accessibility of content stored in Amazon S3 buckets. By acting as an intermediary between users and S3 storage, `fsnode` accelerates content delivery and provides efficient file management.

## Context and Problem Statement

`fsnode` has been implemented to address the challenge of slow download speeds associated with streaming video content from Amazon S3. The choice of using S3 was made to leverage its almost infinite storage capacity at a low cost. Videos are stored in S3 buckets and later accessed through a Flutter application. However, this setup can result in sluggish download times, which is particularly problematic for video streaming. `fsnode` solves this issue by optimizing the delivery process.

## Key Features

`fsnode` is a component of a larger project, designed to work in harmony with other services. Its key features include:

- **RSA Key Pair Generation and CSR Creation**: Generates an RSA key pair and creates a Certificate Signing Request (CSR).
- **Certificate Signing**: Sends the CSR to a Certificate Authority (CA) to obtain a signed certificate.
- **Secure Connections**: Secure connection using TLS.
- **Chunked File Serving**: Serves file content in chunks using HTTP partial content for efficient streaming.
- **S3 Bucket Integration**: Downloads requested files from an AWS S3 bucket to local disk if they are not already present.
- **S3 Object parallel download**: (Future implementation) Download S3 object parts in parallel.
- **Disk Management**: Initiates a disk prune task whenever the local disk content reaches a specified limit.
- **Cluster Operation**: Operates in a cluster where all nodes are part of the same logical disk. The master node can sum up all available space across `fsnode` instances and dispatch requests to nodes with the least load.

With these features, `fsnode` ensures fast, secure, and efficient content delivery, making it an essential tool for managing and distributing large volumes of data.