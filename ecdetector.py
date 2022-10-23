from ast import keyword
import json, sys
import traceback
from cryptodetector import CryptoDetector, Output, Options, Logger, FileLister
from cryptodetector.exceptions import CryptoDetectorError


def scan_for_ec():
    options = Options(CryptoDetector.VERSION).read_all_options()
    try:
        detector = CryptoDetector(options)
        detector.scan()
        return detector.output_file

    except CryptoDetectorError as expn:
        Output.print_error(str(expn))
        FileLister.cleanup_all_tmp_files()

    except KeyboardInterrupt:
        FileLister.cleanup_all_tmp_files()
        raise

    except Exception as expn:
        Output.print_error("Unhandled exception.\n\n" + str(traceback.format_exc()))
        FileLister.cleanup_all_tmp_files()


def reduce_hit_info(hit,file_paths):
    text_before = "\n".join(hit[f"line_text_before_{i}"] for i in range(1,4))
    text_after = "\n".join(hit[f"line_text_after_{i}"] for i in range(1,4))
    return {"text_before":text_before,"text_after":text_after,"text_line":hit["line_text"],"paths":file_paths}


def parse_scan_results(filename):
    with open(filename) as f:
        data = json.load(f)

    crypto_evidence = data['crypto_evidence'].values()

    #sort evidences by curves
    evidence_by_curve = {}
    for evidence in crypto_evidence:
        file_paths = evidence["file_paths"]
        for hit in evidence["hits"]:
            curve_name = hit["matched_text"].lower()
            if curve_name in evidence_by_curve:
                evidence_by_curve[curve_name].append(reduce_hit_info(hit,file_paths))
            else:
                evidence_by_curve[curve_name]=[]

    filename_ec = filename.replace("crypto","ec")
    with open(filename_ec,"w") as f:
        f.write(json.dumps(evidence_by_curve,sort_keys=True, indent=2))

    print(f"\n\nCurves found (more info in {filename_ec}): ")
    print(list(evidence_by_curve.keys()))


if __name__=="__main__":
    filename = scan_for_ec()
    parse_scan_results(filename)
