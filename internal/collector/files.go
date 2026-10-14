package collector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/larslefebvre/kscan/internal/inventory"
)

// FromFiles builds an inventory from YAML/JSON manifests (files or directories,
// walked recursively; "-" reads stdin). Useful for scanning manifests in CI before they reach a
// cluster, and for testing policies without a cluster.
func FromFiles(paths ...string) (*inventory.Inventory, error) {
	inv := inventory.New("files:" + strings.Join(paths, ","))
	inv.Cluster.Name = "manifests: " + strings.Join(paths, ", ")
	for _, root := range paths {
		if root == "-" {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return nil, err
			}
			if err := AddManifests(inv, data); err != nil {
				return nil, fmt.Errorf("stdin: %w", err)
			}
			continue
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !isManifest(path) {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := AddManifests(inv, data); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return inv, nil
}

func isManifest(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml", ".json":
		return true
	}
	return false
}

// AddManifests decodes a (multi-document) YAML or JSON stream into inv.
// `kind: List` documents are flattened.
func AddManifests(inv *inventory.Inventory, data []byte) error {
	docs, err := SplitYAML(data)
	if err != nil {
		return err
	}
	for _, doc := range docs {
		js, err := yaml.YAMLToJSON(doc)
		if err != nil {
			return err
		}
		if len(bytes.TrimSpace(js)) == 0 || string(js) == "null" {
			continue
		}
		// Skip YAML that isn't a Kubernetes object (e.g. kscan policy files
		// living next to manifests).
		var tm struct{ APIVersion, Kind string }
		if err := json.Unmarshal(js, &tm); err != nil || tm.APIVersion == "" || tm.Kind == "" {
			continue
		}
		// unstructured's JSON decoder keeps whole numbers as int64, which
		// matters for CEL comparisons such as runAsUser == 0.
		u := &unstructured.Unstructured{}
		if err := u.UnmarshalJSON(js); err != nil {
			return err
		}
		if u.IsList() {
			list, err := u.ToList()
			if err != nil {
				return err
			}
			for i := range list.Items {
				inv.Add(list.Items[i].Object)
			}
			continue
		}
		inv.Add(u.Object)
	}
	return nil
}

// SplitYAML splits a multi-document YAML stream into individual documents.
func SplitYAML(data []byte) ([][]byte, error) {
	r := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	var docs [][]byte
	for {
		doc, err := r.Read()
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(doc)) > 0 {
			docs = append(docs, doc)
		}
	}
}
