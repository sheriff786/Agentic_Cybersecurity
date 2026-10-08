from eval.download_hf_rows import download


def _fake_fetch(total):
    def fetch(dataset, config, split, offset, length=100):
        end = min(offset + length, total)
        return {"num_rows_total": total,
                "rows": [{"row_idx": i, "row": {"text": f"t{i}", "label": i % 2}} for i in range(offset, end)]}
    return fetch


def test_download_pages_through_the_whole_split():
    rows = download("x/y", "train", fetch=_fake_fetch(250))
    assert len(rows) == 250 and rows[-1]["text"] == "t249"


def test_download_handles_empty_split():
    assert download("x/y", "train", fetch=_fake_fetch(0)) == []
