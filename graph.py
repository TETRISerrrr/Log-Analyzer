from collections import Counter
from pathlib import Path


def create_graph(
    events,
    output: str = "exports/event_types.png"
):

    try:

        import matplotlib.pyplot as plt

    except ImportError:

        raise RuntimeError(
            "matplotlib is not installed. "
            "Run: pip install matplotlib"
        )

    Path(output).parent.mkdir(
        parents=True,
        exist_ok=True
    )

    counts = Counter(
        event.event_type
        for event in events
    )

    if not counts:

        raise RuntimeError(
            "No events available for graph."
        )

    labels = list(
        counts.keys()
    )

    values = list(
        counts.values()
    )

    plt.figure(
        figsize=(10, 5)
    )

    plt.bar(
        labels,
        values
    )

    plt.title(
        "Log Analyzer - Event Types"
    )

    plt.xlabel(
        "Event type"
    )

    plt.ylabel(
        "Number of events"
    )

    plt.xticks(
        rotation=25
    )

    plt.tight_layout()

    plt.savefig(
        output,
        dpi=150
    )

    plt.close()

    return output