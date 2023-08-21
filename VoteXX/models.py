from django.db import models
from django.conf import settings
import copy
import csv
import datetime
import io
import uuid

from VoteXX_auth.jsonfield import JSONField
from VoteXX_auth.models import User, AUTH_SYSTEMS
from VoteXX import datatypes



# Create your models here.


class Flag(models.Model):
    sid = models.AutoField(primary_key=True)
    enc_data = models.BigIntegerField()
    op_time = models.DateField(auto_now_add=True)


class VoteXXModel(models.Model, datatypes.LDObjectContainer):
    class Meta:
        abstract = True

"""
a toy election model
"""
class ToyElection(VoteXXModel):
    # admin for the election, it should be a user of VoteXX
    admin = models.ForeignKey(User, on_delete=models.CASCADE)

    uuid = models.CharField(max_length=50, null=False)

    # election name
    short_name = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=250)

    # help email
    help_email = models.EmailField(null=True)

    # TODO


    @classmethod
    def get_by_uuid(cls, uuid):
        try:
            return cls.objects.select_related().get(uuid=uuid)
        except cls.DoesNotExist:
            return None

    @classmethod
    def get_by_short_name(cls, short_name):
        try:
            return cls.objects.get(short_name=short_name)
        except cls.DoesNotExist:
            return None

    @classmethod
    def get_by_user_as_admin(cls, user, archived_p=None, limit=None):
        query = cls.objects.filter(admin=user)
        if limit:
            return query[:limit]
        else:
            return query

    @classmethod
    def get_by_user_as_voter(cls, user, archived_p=None, limit=None):
        query = cls.objects.filter(voter__user=user)
        if archived_p is True:
            query = query.exclude(archived_at=None)
        if archived_p is False:
            query = query.filter(archived_at=None)
        if limit:
            return query[:limit]
        else:
            return query

"""
draw from helios, a file contains the voters for an election
"""
class VoterFile(models.Model):
    """
    A model to store files that are lists of voters to be processed
    """
    # path where we store voter upload
    PATH = settings.VOTER_UPLOAD_REL_PATH

    election = models.ForeignKey(ToyElection, on_delete=models.CASCADE)

    # we move to storing the content in the DB
    voter_file = models.FileField(upload_to=PATH, max_length=250,null=True)
    voter_file_content = models.TextField(null=True)

    uploaded_at = models.DateTimeField(auto_now_add=True)
    processing_started_at = models.DateTimeField(auto_now_add=False, null=True)
    processing_finished_at = models.DateTimeField(auto_now_add=False, null=True)
    num_voters = models.IntegerField(null=True)


"""
model for voter
"""
class Voter(VoteXXModel):
    # bind to an election
    election = models.ForeignKey(ToyElection, on_delete=models.CASCADE)

    uuid = models.CharField(max_length=50)

    # the voter should be a user
    user = models.ForeignKey('VoteXX_auth.User', null=True, on_delete=models.CASCADE)


    @classmethod
    def get_by_election_and_user(cls, election, user):
        try:
            return cls.objects.get(election=election, user=user)
        except cls.DoesNotExist:
            return None


class CastVote(VoteXXModel):
    # the reference to the voter provides the voter_uuid
    voter = models.ForeignKey(Voter, on_delete=models.CASCADE)

    # the actual encrypted vote
    vote = models.CharField(max_length=100)

    # cache the hash of the vote
    vote_hash = models.CharField(max_length=100)

    # a tiny version of the hash to enable short URLs
    vote_tinyhash = models.CharField(max_length=50, null=True, unique=True)

    cast_at = models.DateTimeField(auto_now_add=True)

    @classmethod
    def get_by_voter(cls, voter):
        return cls.objects.filter(voter=voter).order_by('-cast_at')

    @classmethod
    def get_by_election(cls, election):
        return cls.objects.filter(voter__election=election).order_by('-cast_at')