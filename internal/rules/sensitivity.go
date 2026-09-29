package rules

import (
	"sort"
	"strconv"
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// "One repo compromise reaches your data warehouse" is a sentence someone
// forwards to their manager. "One repo compromise reaches a role" is not. The
// difference is knowing what the end of the chain actually holds, so this file
// classifies a permission set into the thing a person would name.
//
// It errs towards saying less: an unrecognised permission contributes nothing
// rather than being guessed into a category, because naming the wrong data
// store is worse than naming none.

// dataActions are AWS actions that read or change stored data, mapped to what
// a reader would call it.
var dataActions = map[string]string{
	"s3:getobject":                   "S3 objects",
	"s3:listbucket":                  "S3 buckets",
	"s3:putobject":                   "S3 objects (write)",
	"s3:deleteobject":                "S3 objects (delete)",
	"dynamodb:getitem":               "DynamoDB tables",
	"dynamodb:query":                 "DynamoDB tables",
	"dynamodb:scan":                  "DynamoDB tables",
	"rds:describedbinstances":        "RDS databases",
	"rds-data:executestatement":      "RDS data",
	"redshift-data:executestatement": "Redshift",
	"athena:startqueryexecution":     "Athena queries over S3",
	"glue:gettable":                  "the Glue data catalogue",
	"secretsmanager:getsecretvalue":  "Secrets Manager secrets",
	"ssm:getparameter":               "SSM parameters",
	"ssm:getparameters":              "SSM parameters",
	"ssm:getparametersbypath":        "SSM parameters",
	"kms:decrypt":                    "anything encrypted with that KMS key",
	"ses:sendemail":                  "outbound email from your domain",
	"sqs:receivemessage":             "SQS queues",
	"kinesis:getrecords":             "Kinesis streams",
	"es:esthttpget":                  "OpenSearch indices",
	"timestream:select":              "Timestream",
	"elasticfilesystem:clientmount":  "EFS file systems",
	"backup:startrestorejob":         "backups",
	"cloudtrail:deletetrail":         "the audit trail",
}

// dataServices are AWS service prefixes that are about data. A wildcard on one
// of these (s3:*) is a data grant even though no single action matched.
var dataServices = map[string]string{
	"s3":             "S3 buckets",
	"dynamodb":       "DynamoDB tables",
	"rds":            "RDS databases",
	"rds-data":       "RDS data",
	"redshift":       "Redshift",
	"redshift-data":  "Redshift",
	"athena":         "Athena queries over S3",
	"secretsmanager": "Secrets Manager secrets",
	"ssm":            "SSM parameters",
	"kms":            "KMS-encrypted data",
	"glue":           "the Glue data catalogue",
	"kinesis":        "Kinesis streams",
	"es":             "OpenSearch indices",
	"elasticache":    "ElastiCache",
	"docdb":          "DocumentDB",
	"timestream":     "Timestream",
	"qldb":           "QLDB",
}

// computeActions are AWS actions that run code.
var computeServices = map[string]string{
	"lambda":    "Lambda functions",
	"ecs":       "ECS tasks",
	"eks":       "EKS workloads",
	"ec2":       "EC2 instances",
	"batch":     "Batch jobs",
	"sagemaker": "SageMaker notebooks",
}

// gcpDataRoles maps a GCP role prefix to the store it reaches.
var gcpDataRoles = map[string]string{
	"roles/bigquery.dataviewer":                  "BigQuery datasets",
	"roles/bigquery.dataeditor":                  "BigQuery datasets (write)",
	"roles/bigquery.dataowner":                   "BigQuery datasets (owner)",
	"roles/bigquery.admin":                       "BigQuery",
	"roles/bigquery.user":                        "BigQuery queries",
	"roles/storage.objectviewer":                 "Cloud Storage objects",
	"roles/storage.objectadmin":                  "Cloud Storage objects (write)",
	"roles/storage.objectuser":                   "Cloud Storage objects",
	"roles/storage.admin":                        "Cloud Storage",
	"roles/secretmanager.secretaccessor":         "Secret Manager secrets",
	"roles/secretmanager.admin":                  "Secret Manager",
	"roles/cloudsql.client":                      "Cloud SQL databases",
	"roles/cloudsql.admin":                       "Cloud SQL",
	"roles/cloudsql.editor":                      "Cloud SQL",
	"roles/spanner.databasereader":               "Spanner databases",
	"roles/spanner.databaseuser":                 "Spanner databases",
	"roles/spanner.admin":                        "Spanner",
	"roles/datastore.user":                       "Datastore/Firestore",
	"roles/datastore.owner":                      "Datastore/Firestore",
	"roles/bigtable.reader":                      "Bigtable",
	"roles/bigtable.user":                        "Bigtable",
	"roles/pubsub.subscriber":                    "Pub/Sub messages",
	"roles/cloudkms.cryptokeyencrypterdecrypter": "anything encrypted with that KMS key",
	"roles/dataflow.admin":                       "Dataflow pipelines",
	"roles/composer.admin":                       "Composer environments",
	"roles/logging.privatelogviewer":             "private audit logs",
	"roles/healthcare.datasetviewer":             "healthcare datasets",
}

var gcpComputeRoles = map[string]string{
	"roles/run.admin":                "Cloud Run services",
	"roles/run.developer":            "Cloud Run services",
	"roles/cloudfunctions.admin":     "Cloud Functions",
	"roles/cloudfunctions.developer": "Cloud Functions",
	"roles/compute.admin":            "Compute Engine instances",
	"roles/compute.instanceadmin":    "Compute Engine instances",
	"roles/container.admin":          "GKE workloads",
	"roles/container.developer":      "GKE workloads",
	"roles/cloudbuild.builds.editor": "Cloud Build",
	"roles/dataproc.editor":          "Dataproc clusters",
}

// Classify reads a permission set and says what reaching it means. grants are
// IAM actions on AWS and role names on GCP; privileged comes from the rules
// that already decided whether the identity can escalate.
func Classify(provider model.Provider, grants []string, privileged bool) (model.Sensitivity, []string) {
	reach := map[string]bool{}
	sensitivity := model.SensitivityLow

	raise := func(s model.Sensitivity) {
		if s.Weight() > sensitivity.Weight() {
			sensitivity = s
		}
	}
	if privileged {
		raise(model.SensitivityAdmin)
	}

	for _, g := range grants {
		lower := strings.ToLower(strings.TrimSpace(g))
		if lower == "" {
			continue
		}

		if provider == model.ProviderGCP {
			if what, ok := gcpDataRoles[lower]; ok {
				reach[what] = true
				raise(model.SensitivityData)
				continue
			}
			if what, ok := gcpComputeRoles[lower]; ok {
				reach[what] = true
				raise(model.SensitivityCompute)
			}
			continue
		}

		// AWS. "*" on its own is admin, already covered by privileged, but a
		// chain terminal may hold it without any rule having looked at it.
		if lower == "*" || lower == "*:*" {
			raise(model.SensitivityAdmin)
			reach["everything in the account"] = true
			continue
		}
		if what, ok := dataActions[lower]; ok {
			reach[what] = true
			raise(model.SensitivityData)
			continue
		}

		service, verb, ok := strings.Cut(lower, ":")
		if !ok {
			continue
		}
		// A wildcard verb on a data service is a data grant; a specific verb
		// we do not recognise is not, because most of a service's actions are
		// describe calls.
		if strings.HasSuffix(verb, "*") {
			if what, found := dataServices[service]; found {
				reach[what] = true
				raise(model.SensitivityData)
				continue
			}
			if what, found := computeServices[service]; found {
				reach[what] = true
				raise(model.SensitivityCompute)
			}
		}
	}

	out := make([]string, 0, len(reach))
	for r := range reach {
		out = append(out, r)
	}
	sort.Strings(out)
	return sensitivity, out
}

// ClassifyPrincipal fills the sensitivity fields on a principal in place.
func ClassifyPrincipal(p *model.Principal) {
	p.Sensitivity, p.Reach = Classify(p.Provider, p.Grants, p.Privileged)
}

// reachPhrase renders what a terminal holds as the end of a sentence.
func reachPhrase(sensitivity model.Sensitivity, reach []string) string {
	if len(reach) == 0 {
		return sensitivity.Describe()
	}
	switch len(reach) {
	case 1:
		return "reaches " + reach[0]
	case 2:
		return "reaches " + reach[0] + " and " + reach[1]
	default:
		return "reaches " + reach[0] + ", " + reach[1] + " and " +
			strconv.Itoa(len(reach)-2) + " more"
	}
}
