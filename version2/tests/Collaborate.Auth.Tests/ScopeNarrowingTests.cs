using Collaborate.Auth.Core;
using Xunit;

namespace Collaborate.Auth.Tests;

public class ScopeNarrowingTests
{
    [Fact]
    public void Intersect_NarrowsToTheIntersectionOfAllThreeSets()
    {
        var result = ScopeNarrowing.Intersect(
            requested: new[] { "comments.read", "comments.write", "documents.read" },
            subjectScopes: new[] { "comments.read", "comments.write" },
            serviceMaxScopes: new[] { "comments.read" });

        Assert.True(result.SetEquals(new[] { "comments.read" }));
    }

    [Fact]
    public void Intersect_ReturnsEmpty_WhenSubjectNeverHadTheScopeAtAll()
    {
        var result = ScopeNarrowing.Intersect(
            requested: new[] { "financial.read" },
            subjectScopes: new[] { "comments.read" },
            serviceMaxScopes: new[] { "financial.read" });

        Assert.Empty(result);
    }
}
