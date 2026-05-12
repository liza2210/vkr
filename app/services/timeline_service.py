from app.storage.repositories import ArtifactRepository


class TimelineService:
    def __init__(self, session):
        self.artifact_repo = ArtifactRepository(session)

    def build_timeline(self):
        artifacts = self.artifact_repo.list_all()

        artifacts = [
            artifact
            for artifact in artifacts
            if artifact.timestamp_start is not None or artifact.timestamp is not None
        ]

        return sorted(
            artifacts,
            key=lambda artifact: artifact.timestamp_start or artifact.timestamp,
        )
